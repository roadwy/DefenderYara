
rule Trojan_Win32_Ekstak_GNU_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.GNU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 83 c4 14 48 89 35 6c 4c 4d 00 5f 5e a3 68 4c 4d 00 5b c9 c3 55 8b ec 8b 4d 18 8b 45 14 53 56 83 21 00 } //10
		$a_01_1 = {8b 45 fc 83 c4 14 48 89 35 6c 5c 4d 00 5f 5e a3 68 5c 4d 00 5b c9 c3 55 8b ec 8b 4d 18 8b 45 14 53 56 83 21 00 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=10
 
}