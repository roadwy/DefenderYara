
rule Trojan_Win32_Agent_DY{
	meta:
		description = "Trojan:Win32/Agent.DY,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed 81 fb 68 58 4d 56 } //4
		$a_00_1 = {52 65 6d 6f 74 65 5f 32 30 31 30 2e 30 38 2e 30 33 } //1 Remote_2010.08.03
		$a_00_2 = {21 2a 5f 2a 2d 3e 73 65 76 65 6e 2d 65 6c 65 76 65 6e 3c 2d 2a 5f 2a 21 } //1 !*_*->seven-eleven<-*_*!
		$a_00_3 = {25 73 25 73 25 73 28 25 64 29 25 73 } //1 %s%s%s(%d)%s
		$a_00_4 = {25 73 25 64 2e 64 61 74 } //1 %s%d.dat
		$a_00_5 = {5c 78 78 78 78 78 78 78 2e 64 62 67 } //1 \xxxxxxx.dbg
	condition:
		((#a_01_0  & 1)*4+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}