
rule Trojan_BAT_Kryptik_CS_eml{
	meta:
		description = "Trojan:BAT/Kryptik.CS!eml,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4b 75 72 64 69 73 68 43 6f 64 65 72 50 72 6f 64 75 63 74 73 } //1 KurdishCoderProducts
		$a_01_1 = {52 61 7a 65 72 49 6e 73 69 64 65 72 } //1 RazerInsider
		$a_01_2 = {52 00 61 00 7a 00 65 00 72 00 50 00 61 00 6e 00 65 00 6c 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 RazerPanel.Properties.Resources
		$a_01_3 = {52 00 61 00 7a 00 65 00 72 00 50 00 61 00 6e 00 65 00 6c 00 2e 00 65 00 78 00 65 00 } //1 RazerPanel.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}