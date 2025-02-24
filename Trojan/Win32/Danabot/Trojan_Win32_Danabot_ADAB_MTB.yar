
rule Trojan_Win32_Danabot_ADAB_MTB{
	meta:
		description = "Trojan:Win32/Danabot.ADAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {51 00 1c 0f 51 ?? ?? ?? ?? ?? ?? 0f 51 00 ae 0f 51 00 ae 0f 51 00 c4 0f 51 00 ed 0f 51 00 80 0f 51 ?? ?? ?? ?? ?? ?? 0f 51 00 30 0f 51 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}