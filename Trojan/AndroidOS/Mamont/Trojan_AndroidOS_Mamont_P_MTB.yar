
rule Trojan_AndroidOS_Mamont_P_MTB{
	meta:
		description = "Trojan:AndroidOS/Mamont.P!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {4c 70 75 74 31 63 6d 64 2f 70 75 74 31 72 6f 6f 74 } //1 Lput1cmd/put1root
		$a_01_1 = {4c 70 75 74 69 73 6e 61 72 65 2f 70 75 74 31 73 74 72 69 6b 65 } //1 Lputisnare/put1strike
		$a_01_2 = {70 75 74 31 78 70 6c 6f 69 74 } //1 put1xploit
		$a_01_3 = {4c 70 75 74 69 77 61 72 65 2f 70 75 74 31 64 72 69 76 65 } //1 Lputiware/put1drive
		$a_01_4 = {4c 70 75 74 69 30 70 65 72 2f 70 75 74 31 72 6f 6f 74 } //1 Lputi0per/put1root
		$a_01_5 = {4c 70 75 74 31 64 72 69 76 65 2f 70 75 74 31 64 61 65 6d 6f 6e } //1 Lput1drive/put1daemon
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}