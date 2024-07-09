
rule Trojan_Win32_CryptInject_MA_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d 08 03 4d fc 0f b6 09 8b 45 fc 99 be ?? ?? ?? ?? f7 fe 8b 45 ec 0f b6 14 10 33 ca 8b 45 f8 03 45 fc 88 08 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}