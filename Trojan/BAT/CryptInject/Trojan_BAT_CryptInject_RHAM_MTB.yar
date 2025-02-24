
rule Trojan_BAT_CryptInject_RHAM_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.RHAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_00_0 = {73 00 6d 00 69 00 74 00 68 00 70 00 72 00 6f 00 70 00 65 00 72 00 74 00 79 00 73 00 6f 00 6c 00 75 00 74 00 69 00 6f 00 6e 00 73 00 2e 00 63 00 6f 00 6d 00 2f 00 43 00 72 00 79 00 70 00 74 00 6f 00 2e 00 65 00 78 00 65 00 } //3 smithpropertysolutions.com/Crypto.exe
		$a_03_1 = {50 45 00 00 4c 01 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 30 00 00 0a 00 00 00 08 00 00 00 00 00 00 5a 28 } //2
	condition:
		((#a_00_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}