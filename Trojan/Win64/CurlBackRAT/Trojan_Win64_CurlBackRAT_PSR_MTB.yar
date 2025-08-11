
rule Trojan_Win64_CurlBackRAT_PSR_MTB{
	meta:
		description = "Trojan:Win64/CurlBackRAT.PSR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {2f 64 6e 61 6d 6d 6f 63 6d 76 69 74 6e 61 } //1 /dnammocmvitna
		$a_81_1 = {61 6e 74 69 2d 76 6d 2e 74 78 74 } //1 anti-vm.txt
		$a_81_2 = {4e 4f 20 43 50 55 20 46 41 4e 20 46 4f 55 4e 44 20 2c 20 45 58 49 54 49 4e 47 20 21 } //1 NO CPU FAN FOUND , EXITING !
		$a_81_3 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 41 6e 74 69 56 69 72 75 73 50 72 6f 64 75 63 74 } //1 SELECT * FROM AntiVirusProduct
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}