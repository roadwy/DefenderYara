
rule Ransom_Win64_FunkSec_GNM_MTB{
	meta:
		description = "Ransom:Win64/FunkSec.GNM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 75 6e 6b 69 79 64 6b 37 63 36 6a 33 76 76 63 6b 35 7a 6b 32 67 69 6d 6c 32 75 37 34 36 66 61 35 69 72 77 61 6c 77 32 6b 6a 65 6d 36 74 76 6f 66 6a 69 37 72 77 69 64 2e 6f 6e 69 6f 6e } //1 funkiydk7c6j3vvck5zk2giml2u746fa5irwalw2kjem6tvofji7rwid.onion
		$a_01_1 = {64 65 76 69 63 65 20 68 61 73 20 62 65 65 6e 20 73 75 63 63 65 73 73 66 75 6c 6c 79 20 69 6e 66 69 6c 74 72 61 74 65 64 20 62 79 20 66 75 6e 6b 73 65 63 20 72 61 6e 73 6f 6d 77 61 72 65 21 } //1 device has been successfully infiltrated by funksec ransomware!
		$a_01_2 = {62 63 31 71 72 67 68 6e 74 36 63 71 64 73 78 74 30 71 6d 6c 63 61 71 30 77 63 61 76 71 36 70 6d 66 6d 38 32 76 74 78 66 65 71 } //1 bc1qrghnt6cqdsxt0qmlcaq0wcavq6pmfm82vtxfeq
		$a_01_3 = {44 6f 20 4e 4f 54 20 61 74 74 65 6d 70 74 20 74 6f 20 74 61 6d 70 65 72 20 77 69 74 68 20 66 69 6c 65 73 20 6f 72 20 73 79 73 74 65 6d 73 } //1 Do NOT attempt to tamper with files or systems
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}