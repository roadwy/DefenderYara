
rule TrojanDownloader_O97M_Powdow_MJP_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.MJP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b 69 6d 20 2b 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 6d 65 64 69 61 66 69 72 65 2e 63 6f 6d 2f 66 69 6c 65 2f 68 39 73 72 77 64 6e 70 37 39 64 39 74 34 39 2f 31 30 2e 74 78 74 2f 66 69 6c 65 } //01 00  kim + "https://www.mediafire.com/file/h9srwdnp79d9t49/10.txt/file
		$a_01_1 = {27 29 20 2d 75 73 65 42 29 20 7c 20 2e 28 27 7b 78 7d 7b 39 7d 27 2e 72 65 70 6c 61 63 65 28 27 39 27 2c 27 30 27 29 2e 72 65 70 6c 61 63 65 28 27 78 27 2c 27 31 27 29 2d 66 27 4b 49 41 49 53 49 53 41 27 2c 27 2a 2a 2a 2a 2a 27 29 2e 72 65 70 6c 61 63 65 28 27 2a 2a 2a 2a 2a 27 2c 27 49 27 29 2e 72 65 70 6c 61 63 65 28 27 4b 49 41 49 53 49 53 41 27 2c 27 45 58 27 29 } //01 00  ') -useB) | .('{x}{9}'.replace('9','0').replace('x','1')-f'KIAISISA','*****').replace('*****','I').replace('KIAISISA','EX')
		$a_01_2 = {3d 20 22 5e 2a 77 3f 72 73 68 3f 3e 3e 22 } //00 00  = "^*w?rsh?>>"
	condition:
		any of ($a_*)
 
}