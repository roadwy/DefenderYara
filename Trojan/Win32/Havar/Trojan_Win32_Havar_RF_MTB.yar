
rule Trojan_Win32_Havar_RF_MTB{
	meta:
		description = "Trojan:Win32/Havar.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {ba 20 0a 00 00 8d 04 12 0f af c2 8b c8 0f af c8 8b c2 f7 ea 2b c8 8b c1 } //2
		$a_01_1 = {6a 61 67 76 69 6c 6c 68 61 64 69 67 } //1 jagvillhadig
		$a_01_2 = {6d 73 69 75 73 65 72 64 65 73 6b 2e 64 61 74 } //1 msiuserdesk.dat
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}