
rule Trojan_BAT_LummaC_ASGE_MTB{
	meta:
		description = "Trojan:BAT/LummaC.ASGE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {51 00 7a 00 70 00 63 00 56 00 32 00 6c 00 75 00 5a 00 47 00 39 00 33 00 63 00 31 00 78 00 4e 00 61 00 57 00 4e 00 79 00 62 00 33 00 4e 00 76 00 5a 00 6e 00 51 00 75 00 54 00 6b 00 56 00 55 00 58 00 45 00 5a 00 79 00 59 00 57 00 31 00 6c 00 64 00 32 00 39 00 79 00 61 00 31 00 78 00 32 00 4e 00 43 00 34 00 77 00 4c 00 6a 00 4d 00 77 00 4d 00 7a 00 45 00 35 00 58 00 45 00 31 00 54 00 51 00 6e 00 56 00 70 00 62 00 47 00 51 00 75 00 5a 00 58 00 68 00 6c 00 } //5 QzpcV2luZG93c1xNaWNyb3NvZnQuTkVUXEZyYW1ld29ya1x2NC4wLjMwMzE5XE1TQnVpbGQuZXhl
	condition:
		((#a_01_0  & 1)*5) >=5
 
}