
rule Trojan_BAT_Smokeloader_JN_MTB{
	meta:
		description = "Trojan:BAT/Smokeloader.JN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_03_0 = {0c 1d 2c de 07 08 07 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 07 08 07 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 07 17 6f ?? ?? ?? 0a 06 07 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 0d } //10
		$a_80_1 = {4b 6a 79 73 75 77 6a 72 6e 77 68 } //Kjysuwjrnwh  1
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_80_3 = {43 67 70 7a 76 72 67 78 6f 64 77 63 79 6d 78 6c 72 74 7a 62 6f 69 73 } //Cgpzvrgxodwcymxlrtzbois  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1+(#a_80_3  & 1)*1) >=13
 
}