
rule Trojan_BAT_DiskKill_RPX_MTB{
	meta:
		description = "Trojan:BAT/DiskKill.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {76 69 72 75 73 74 68 69 6e 67 } //1 virusthing
		$a_01_1 = {48 61 63 6b 69 6e 67 20 73 74 75 66 66 } //1 Hacking stuff
		$a_01_2 = {62 00 69 00 6e 00 67 00 62 00 6f 00 6e 00 67 00 } //1 bingbong
		$a_01_3 = {74 00 61 00 6b 00 65 00 6f 00 77 00 6e 00 2e 00 65 00 78 00 65 00 } //1 takeown.exe
		$a_01_4 = {66 00 72 00 69 00 65 00 6e 00 64 00 6c 00 2e 00 64 00 6c 00 6c 00 } //1 friendl.dll
		$a_01_5 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 54 00 61 00 73 00 6b 00 4d 00 67 00 72 00 } //1 DisableTaskMgr
		$a_01_6 = {62 00 69 00 6e 00 5c 00 6d 00 61 00 72 00 6b 00 65 00 72 00 2e 00 74 00 78 00 74 00 } //1 bin\marker.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}