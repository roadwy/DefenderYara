
rule Ransom_MSIL_RyukCrypt_PG_MTB{
	meta:
		description = "Ransom:MSIL/RyukCrypt.PG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 70 70 4d 75 74 65 78 52 75 6e } //1 appMutexRun
		$a_01_1 = {3c 00 45 00 6e 00 63 00 79 00 70 00 74 00 65 00 64 00 4b 00 65 00 79 00 3e 00 } //1 <EncyptedKey>
		$a_01_2 = {5c 00 72 00 65 00 61 00 64 00 5f 00 69 00 74 00 2e 00 74 00 78 00 74 00 } //1 \read_it.txt
		$a_01_3 = {59 00 6f 00 75 00 20 00 48 00 61 00 76 00 65 00 20 00 42 00 65 00 65 00 6e 00 20 00 48 00 61 00 63 00 6b 00 65 00 64 00 21 00 } //1 You Have Been Hacked!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}