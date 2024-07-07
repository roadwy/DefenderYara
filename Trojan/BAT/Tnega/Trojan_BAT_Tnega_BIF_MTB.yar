
rule Trojan_BAT_Tnega_BIF_MTB{
	meta:
		description = "Trojan:BAT/Tnega.BIF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 73 3a 2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f 38 39 35 34 39 34 39 36 33 35 31 35 37 37 32 39 33 31 2f 38 39 35 35 39 31 30 35 37 32 35 31 37 36 32 31 38 36 2f 74 65 73 74 5f 32 2e 64 6c 6c } //1 https://cdn.discordapp.com/attachments/895494963515772931/895591057251762186/test_2.dll
		$a_01_1 = {42 00 65 00 6e 00 74 00 65 00 6e 00 66 00 6f 00 72 00 6d 00 2e 00 42 00 65 00 6e 00 74 00 65 00 6e 00 66 00 6f 00 72 00 6d 00 } //1 Bentenform.Bentenform
		$a_81_2 = {5f 5f 53 74 61 74 69 63 41 72 72 61 79 49 6e 69 74 54 79 70 65 53 69 7a 65 3d 38 37 } //1 __StaticArrayInitTypeSize=87
	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}