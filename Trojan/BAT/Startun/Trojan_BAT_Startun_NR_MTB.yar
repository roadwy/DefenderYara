
rule Trojan_BAT_Startun_NR_MTB{
	meta:
		description = "Trojan:BAT/Startun.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {28 9d 00 00 0a 0b 07 02 7b ?? 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 07 72 ?? 06 00 70 6f ?? 00 00 0a 03 0c 03 28 ?? 00 00 0a 28 ?? 00 00 0a 08 } //2
		$a_01_1 = {69 6e 73 74 61 6c 61 72 63 65 72 74 73 52 65 69 6e 73 74 61 6c 6c 61 6e 64 65 6c 65 74 65 } //1 instalarcertsReinstallandelete
		$a_01_2 = {64 65 6c 65 74 65 4f 74 68 65 72 73 43 65 72 74 69 66 69 63 61 74 65 } //1 deleteOthersCertificate
		$a_01_3 = {45 73 74 61 49 6e 73 74 61 6c 61 64 6f 45 6c 43 65 72 74 } //1 EstaInstaladoElCert
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}