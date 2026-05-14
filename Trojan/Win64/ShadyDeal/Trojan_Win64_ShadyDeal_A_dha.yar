
rule Trojan_Win64_ShadyDeal_A_dha{
	meta:
		description = "Trojan:Win64/ShadyDeal.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {72 61 6e 73 6f 6d 65 2d 61 73 2d 61 2d 73 65 72 76 69 63 65 } //1 ransome-as-a-service
		$a_01_1 = {43 3a 5c 55 73 65 72 73 5c 50 63 5c 76 63 72 65 70 6f 5c 76 63 70 6b 67 5c } //1 C:\Users\Pc\vcrepo\vcpkg\
		$a_01_2 = {5b 00 45 00 52 00 52 00 4f 00 52 00 5d 00 20 00 46 00 69 00 6c 00 65 00 20 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 69 00 6e 00 67 00 20 00 66 00 61 00 69 00 6c 00 65 00 64 00 3a 00 } //1 [ERROR] File processing failed:
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}