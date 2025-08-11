
rule Ransom_Linux_Sarcoma_A_MTB{
	meta:
		description = "Ransom:Linux/Sarcoma.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 41 49 4c 5f 53 54 41 54 45 5f 4e 4f 54 49 46 49 43 41 54 49 4f 4e 2e 70 64 66 } //1 FAIL_STATE_NOTIFICATION.pdf
		$a_01_1 = {76 69 6d 2d 63 6d 64 20 76 6d 73 76 63 2f 73 6e 61 70 73 68 6f 74 2e 72 65 6d 6f 76 65 61 6c 6c } //1 vim-cmd vmsvc/snapshot.removeall
		$a_01_2 = {44 89 d0 44 0f b6 cb 44 89 d9 c1 e8 18 c1 e9 10 44 8b 06 0f b6 d0 46 33 04 8d 80 bc 42 00 48 89 f8 44 0f b6 c9 44 33 04 95 80 b0 42 00 41 0f b6 ca 0f b6 d4 44 89 d8 46 33 04 8d 80 b4 42 00 c1 e8 18 44 8b 4e 04 44 33 0c 8d 80 bc 42 00 89 f9 44 33 04 95 80 b8 42 00 0f b6 d0 c1 e9 10 44 33 0c 95 80 b0 42 00 0f b6 d7 0f b6 c1 41 0f b6 cb c1 eb 10 44 33 0c 85 80 b4 42 00 89 f8 c1 e8 18 44 33 0c 95 80 b8 42 00 8b 56 08 33 14 8d 80 bc 42 00 0f b6 c8 0f b6 c3 33 14 8d 80 b0 42 00 4c 89 d1 c1 eb 08 33 14 85 80 b4 42 00 0f b6 c5 41 c1 ea 10 33 14 85 80 b8 42 00 40 0f b6 c7 8b 4e 0c 33 0c 85 80 bc 42 00 0f b6 c3 41 0f b6 fa 33 0c 85 80 b0 42 00 4c 89 db 33 0c bd 80 b4 42 00 0f b6 c7 33 0c 85 80 b8 42 00 44 89 c7 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}