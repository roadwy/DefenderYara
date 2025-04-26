
rule Trojan_BAT_ClipBanker_ABAT_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.ABAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {50 45 47 41 53 55 53 5f 4c 49 4d 45 2e 44 65 73 69 67 6e 2e 41 6c 67 6f 72 69 74 68 6d 6f 73 2e 4f 76 65 72 6b 69 6c 6c } //1 PEGASUS_LIME.Design.Algorithmos.Overkill
		$a_01_1 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 53 74 72 65 61 6d } //1 GetManifestResourceStream
		$a_01_2 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
		$a_01_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_5 = {50 45 47 41 53 55 53 5f 4c 49 4d 45 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 PEGASUS_LIME.Properties.Resources.resources
		$a_01_6 = {50 45 47 41 53 55 53 5f 4c 49 4d 45 2e 50 72 6f 70 65 72 74 69 65 73 } //1 PEGASUS_LIME.Properties
		$a_01_7 = {24 31 33 34 36 35 63 65 34 2d 31 39 38 37 2d 34 34 36 62 2d 62 36 62 62 2d 30 63 35 38 37 62 64 36 62 33 35 66 } //1 $13465ce4-1987-446b-b6bb-0c587bd6b35f
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}