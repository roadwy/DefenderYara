
rule Trojan_Win64_Tedy_AHO_MTB{
	meta:
		description = "Trojan:Win64/Tedy.AHO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,ffffffb4 00 ffffffb4 00 06 00 00 "
		
	strings :
		$a_81_0 = {44 65 63 72 79 70 74 47 63 6d 56 31 30 20 66 61 69 6c 65 64 3a 20 62 6c 6f 62 4c 65 6e 3d 25 64 2c 20 70 61 79 6c 6f 61 64 4c 65 6e 3d 25 64 2c 20 63 74 4c 65 6e 3d 25 64 2c 20 73 74 61 74 75 73 3d 30 78 25 30 38 58 } //60 DecryptGcmV10 failed: blobLen=%d, payloadLen=%d, ctLen=%d, status=0x%08X
		$a_81_1 = {25 73 5c 25 73 5c 4c 6f 63 61 6c 20 53 74 61 74 65 } //50 %s\%s\Local State
		$a_81_2 = {5c 6f 75 74 70 75 74 5c 67 63 6d 5f 76 31 30 5f 64 65 62 75 67 2e 74 78 74 } //40 \output\gcm_v10_debug.txt
		$a_81_3 = {42 72 61 76 65 53 6f 66 74 77 61 72 65 5c 42 72 61 76 65 2d 42 72 6f 77 73 65 72 5c 55 73 65 72 20 44 61 74 61 } //15 BraveSoftware\Brave-Browser\User Data
		$a_81_4 = {47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 } //10 Google\Chrome\User Data
		$a_81_5 = {4d 69 63 72 6f 73 6f 66 74 5c 45 64 67 65 5c 55 73 65 72 20 44 61 74 61 } //5 Microsoft\Edge\User Data
	condition:
		((#a_81_0  & 1)*60+(#a_81_1  & 1)*50+(#a_81_2  & 1)*40+(#a_81_3  & 1)*15+(#a_81_4  & 1)*10+(#a_81_5  & 1)*5) >=180
 
}