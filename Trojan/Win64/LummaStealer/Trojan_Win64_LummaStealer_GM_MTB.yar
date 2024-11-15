
rule Trojan_Win64_LummaStealer_GM_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 63 46 56 76 4a 61 63 6c 70 72 } //4 main.cFVvJaclpr
		$a_01_1 = {6d 61 69 6e 2e 6f 65 70 4e 65 53 6d 4b 67 54 } //1 main.oepNeSmKgT
		$a_01_2 = {6d 61 69 6e 2e 4d 64 35 45 6e 63 6f 64 65 } //1 main.Md5Encode
		$a_01_3 = {6d 61 69 6e 2e 63 51 50 75 62 44 4e 5a 4e 6a } //4 main.cQPubDNZNj
		$a_01_4 = {6d 61 69 6e 2e 52 44 46 } //1 main.RDF
		$a_01_5 = {6d 61 69 6e 2e 6e 65 4a 44 50 62 4c 52 57 44 } //1 main.neJDPbLRWD
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*4+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}