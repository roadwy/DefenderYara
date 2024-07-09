
rule Trojan_BAT_Cordimik_ABEZ_MTB{
	meta:
		description = "Trojan:BAT/Cordimik.ABEZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {0b 07 16 73 ?? ?? ?? 0a 0c 73 ?? ?? ?? 0a 0d 08 09 6f ?? ?? ?? 0a 04 09 6f ?? ?? ?? 0a 51 de 1e 09 2c 06 09 6f ?? ?? ?? 0a dc } //2
		$a_01_1 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
		$a_01_2 = {4e 65 62 53 74 75 62 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //1 NebStub.Form1.resources
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}