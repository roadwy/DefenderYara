
rule Trojan_Win32_Neoreblamy_NMW_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NMW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {7c b4 8b 7c 24 10 8b 74 24 14 47 89 7c 24 10 } //1
		$a_01_1 = {7e 05 83 fe ff 75 07 8b 7d fc 4b 89 75 fc 85 db 79 d0 8b 45 14 46 } //1
		$a_03_2 = {55 8b ec 8b 45 08 56 8b f1 83 66 04 00 c7 06 ?? ?? ?? ?? c6 46 08 00 ff 30 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2) >=4
 
}