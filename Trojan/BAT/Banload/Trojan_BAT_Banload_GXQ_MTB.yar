
rule Trojan_BAT_Banload_GXQ_MTB{
	meta:
		description = "Trojan:BAT/Banload.GXQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {2e 4e 45 54 20 52 65 61 63 74 6f 72 } //.NET Reactor  1
		$a_80_1 = {2f 63 20 6e 65 74 20 73 74 6f 70 20 4d 65 6d 44 72 76 20 26 20 73 63 20 64 65 6c 65 74 65 20 4d 65 6d 44 72 76 20 26 20 73 63 20 73 74 6f 70 20 4b 50 72 6f 63 65 73 73 48 61 63 6b 65 72 32 } ///c net stop MemDrv & sc delete MemDrv & sc stop KProcessHacker2  1
		$a_80_2 = {73 63 20 64 65 6c 65 74 65 20 4b 50 72 6f 63 65 73 73 48 61 63 6b 65 72 32 20 26 20 73 63 20 73 74 6f 70 20 57 69 6e 4d 52 57 32 20 26 20 73 63 20 64 65 6c 65 74 65 20 57 69 6e 4d 52 57 32 } //sc delete KProcessHacker2 & sc stop WinMRW2 & sc delete WinMRW2  1
		$a_80_3 = {5c 63 72 65 64 65 6e 74 69 61 6c 73 2e 64 61 74 } //\credentials.dat  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}