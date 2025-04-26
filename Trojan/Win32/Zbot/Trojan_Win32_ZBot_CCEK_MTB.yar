
rule Trojan_Win32_ZBot_CCEK_MTB{
	meta:
		description = "Trojan:Win32/ZBot.CCEK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 ec 8b 02 33 45 e0 8b 55 ec 89 02 66 c7 45 d4 ?? ?? 8b 45 ec 83 c0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}