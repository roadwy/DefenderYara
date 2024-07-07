
rule Ransom_MSIL_Cryptolocker_EU_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.EU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {75 6e 6c 6f 63 6b 20 79 6f 75 72 20 66 69 6c 65 73 2e 6c 6e 6b } //1 unlock your files.lnk
		$a_81_1 = {62 79 74 65 73 54 6f 42 65 45 6e 63 72 79 70 74 65 64 } //1 bytesToBeEncrypted
		$a_81_2 = {66 69 6c 65 73 2f 61 6c 65 72 74 6d 73 67 2e 7a 69 70 } //1 files/alertmsg.zip
		$a_81_3 = {46 69 6c 65 45 6e 63 72 79 70 74 69 6f 6e } //1 FileEncryption
		$a_81_4 = {72 6f 40 74 62 40 6c 61 40 75 2e 40 65 75 40 3a 31 40 35 33 } //1 ro@tb@la@u.@eu@:1@53
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}