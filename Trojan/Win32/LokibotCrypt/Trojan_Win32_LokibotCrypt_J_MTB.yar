
rule Trojan_Win32_LokibotCrypt_J_MTB{
	meta:
		description = "Trojan:Win32/LokibotCrypt.J!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 5d fc 8a 1c 03 80 f3 90 01 01 8b ca 03 c8 73 05 e8 90 01 04 88 19 80 31 90 01 01 40 4e 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}