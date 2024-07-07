
rule Trojan_BAT_Zusy_GPAE_MTB{
	meta:
		description = "Trojan:BAT/Zusy.GPAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //1 \AppData\Local\Google\Chrome\User Data\Default\Login Data
		$a_81_1 = {5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 4c 6f 63 61 6c 20 53 74 61 74 65 } //1 \AppData\Local\Google\Chrome\User Data\Local State
		$a_81_2 = {5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 4d 69 63 72 6f 73 6f 66 74 5c 70 72 6f 74 65 63 74 73 2e 7a 69 70 } //1 \AppData\Roaming\Microsoft\protects.zip
		$a_01_3 = {73 00 61 00 6d 00 2e 00 7a 00 69 00 70 00 } //1 sam.zip
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}