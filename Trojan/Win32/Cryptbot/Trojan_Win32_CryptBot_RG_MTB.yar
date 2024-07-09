
rule Trojan_Win32_CryptBot_RG_MTB{
	meta:
		description = "Trojan:Win32/CryptBot.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec a1 ?? ?? ?? ?? 0f af ca 8b 55 08 89 14 88 5d c3 [0-15] 55 8b ec a1 ?? ?? ?? ?? 8b 55 08 89 14 88 5d c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}