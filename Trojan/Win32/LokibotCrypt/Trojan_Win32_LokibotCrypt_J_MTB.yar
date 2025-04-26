
rule Trojan_Win32_LokibotCrypt_J_MTB{
	meta:
		description = "Trojan:Win32/LokibotCrypt.J!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 5d fc 8a 1c 03 80 f3 ?? 8b ca 03 c8 73 05 e8 ?? ?? ?? ?? 88 19 80 31 ?? 40 4e 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}