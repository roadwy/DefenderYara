
rule Trojan_Win64_RootkitDrv_RTC_MTB{
	meta:
		description = "Trojan:Win64/RootkitDrv.RTC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_81_0 = {5c 46 69 76 65 53 79 73 5f 31 5c 78 36 34 5c 44 65 62 75 67 5c 46 69 76 65 53 79 73 2e 70 64 62 } //10 \FiveSys_1\x64\Debug\FiveSys.pdb
		$a_81_1 = {4b 65 42 75 67 43 68 65 63 6b 45 78 } //1 KeBugCheckEx
		$a_81_2 = {6e 74 6f 73 6b 72 6e 6c 2e 65 78 65 } //1 ntoskrnl.exe
		$a_81_3 = {51 32 79 64 30 5c 2a 64 30 5c 2a 64 30 5c 2a } //1 Q2yd0\*d0\*d0\*
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=12
 
}