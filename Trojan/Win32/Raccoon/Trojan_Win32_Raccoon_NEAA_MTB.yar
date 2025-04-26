
rule Trojan_Win32_Raccoon_NEAA_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 ff 83 e0 2c 33 f0 03 ce 8b 55 0c 03 55 fc 88 0a 0f be 45 fb } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}