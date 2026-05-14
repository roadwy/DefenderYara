
rule Trojan_Win64_Zusy_LRC_MTB{
	meta:
		description = "Trojan:Win64/Zusy.LRC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 06 00 00 "
		
	strings :
		$a_81_0 = {5b 2b 5d 20 50 45 20 64 61 74 61 20 3a 20 30 78 25 70 } //1 [+] PE data : 0x%p
		$a_81_1 = {5b 2d 5d 20 4e 6f 74 20 61 20 50 45 20 66 69 6c 65 } //2 [-] Not a PE file
		$a_81_2 = {46 61 69 6c 65 64 20 69 6e 20 52 65 6c 6f 63 61 74 69 6e 67 20 49 6d 61 67 65 } //3 Failed in Relocating Image
		$a_81_3 = {5b 2b 5d 20 6d 69 6d 69 20 64 65 63 72 79 70 74 65 64 } //4 [+] mimi decrypted
		$a_81_4 = {5b 2d 5d 20 4c 6f 63 61 6c 20 4d 61 69 6e 20 48 6f 6c 6c 6f 77 69 6e 67 20 46 61 69 6c 65 64 } //5 [-] Local Main Hollowing Failed
		$a_81_5 = {5b 2b 5d 20 6d 61 69 6e 54 68 72 65 61 64 20 73 75 73 70 65 6e 64 65 64 } //6 [+] mainThread suspended
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*2+(#a_81_2  & 1)*3+(#a_81_3  & 1)*4+(#a_81_4  & 1)*5+(#a_81_5  & 1)*6) >=21
 
}