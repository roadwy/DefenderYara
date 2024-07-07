
rule Trojan_Win32_StealerC_ALAA_MTB{
	meta:
		description = "Trojan:Win32/StealerC.ALAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 85 f8 f7 ff ff 8d 0c 30 e8 4e ff ff ff 30 01 83 fb 0f 75 19 57 8d 85 fc f7 ff ff 50 57 57 57 57 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}