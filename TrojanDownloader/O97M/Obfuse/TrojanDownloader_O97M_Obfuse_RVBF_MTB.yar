
rule TrojanDownloader_O97M_Obfuse_RVBF_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVBF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {24 68 74 7e 74 70 5e 3a 2f 2f 5e 75 70 7e 70 67 24 72 65 24 64 65 60 2e 5e 73 63 40 69 65 5e 6e 63 65 60 6f 6e 74 7e 68 65 5e 77 65 5e 62 40 2e 6e 7e 65 74 5e 2f 66 60 69 6c 7e 65 2f 5e 75 70 6c 24 6f 24 61 64 5e 2f 6c 24 69 7e 73 74 2e 7e 70 68 70 } //1 $ht~tp^://^up~pg$re$de`.^sc@ie^nce`ont~he^we^b@.n~et^/f`il~e/^upl$o$ad^/l$i~st.~php
		$a_01_1 = {3d 72 65 70 6c 61 63 65 28 73 2c 6b 2c 22 22 29 } //1 =replace(s,k,"")
		$a_01_2 = {67 65 74 6f 62 6a 65 63 74 28 75 6e 70 63 6b 28 31 29 29 } //1 getobject(unpck(1))
		$a_01_3 = {61 75 74 6f 6f 70 65 6e 28 29 6f 6e 65 72 72 6f 72 72 65 73 75 6d 65 6e 65 78 74 } //1 autoopen()onerrorresumenext
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}