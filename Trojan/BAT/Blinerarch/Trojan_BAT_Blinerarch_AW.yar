
rule Trojan_BAT_Blinerarch_AW{
	meta:
		description = "Trojan:BAT/Blinerarch.AW,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 44 41 54 41 5b 66 6c 61 73 68 73 65 74 75 70 5d 5d 3e 3c 2f 64 65 73 63 72 69 70 74 69 6f 6e 3e 3c 69 64 3e } //1 CDATA[flashsetup]]></description><id>
		$a_01_1 = {5a 69 70 46 6c 61 73 68 2e 65 78 65 } //1 ZipFlash.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}