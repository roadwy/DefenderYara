
rule Trojan_Win64_GoCoder_MA_MTB{
	meta:
		description = "Trojan:Win64/GoCoder.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0a 00 00 "
		
	strings :
		$a_01_0 = {62 63 31 71 71 78 63 6b 37 6b 70 7a 67 76 75 64 37 76 32 68 66 79 6b 35 35 79 72 34 35 66 6e 6d 6c 34 72 6d 74 33 6a 61 73 7a } //5 bc1qqxck7kpzgvud7v2hfyk55yr45fnml4rmt3jasz
		$a_01_1 = {70 72 69 76 61 74 65 20 6b 65 79 20 69 73 20 6e 6f 74 20 72 69 67 68 74 2e 20 63 6f 6e 74 61 63 74 20 79 6f 75 72 20 61 64 6d 69 6e 69 73 74 72 61 74 6f 72 } //1 private key is not right. contact your administrator
		$a_01_2 = {49 54 53 53 48 4f 57 4b 45 59 } //1 ITSSHOWKEY
		$a_01_3 = {65 6e 63 20 64 6f 6e 65 20 21 } //1 enc done !
		$a_01_4 = {70 75 62 6c 69 63 2e 74 78 74 } //1 public.txt
		$a_01_5 = {64 65 63 72 79 70 74 20 66 69 6c 65 } //1 decrypt file
		$a_01_6 = {49 20 61 6d 20 73 6f 20 73 6f 72 72 79 20 21 20 41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 64 20 62 79 20 52 53 41 2d 31 30 32 34 } //1 I am so sorry ! All your files have been encryptd by RSA-1024
		$a_01_7 = {65 6c 73 65 20 79 6f 75 20 63 61 6e 20 64 65 6c 65 74 65 20 79 6f 75 72 20 65 6e 63 72 79 70 74 65 64 20 64 61 74 61 20 6f 72 20 72 65 69 6e 73 74 61 6c 6c } //1 else you can delete your encrypted data or reinstall
		$a_01_8 = {79 6f 75 20 6e 6f 74 20 6f 77 6e 20 62 69 74 63 6f 69 6e 2c 79 6f 75 20 63 61 6e 20 62 75 79 20 69 74 20 6f 6e 6c 69 6e 65 20 6f 6e 20 73 6f 6d 65 20 77 65 62 73 69 74 65 73 } //1 you not own bitcoin,you can buy it online on some websites
		$a_01_9 = {65 6d 61 69 6c 20 49 54 53 45 4d 41 49 4c 20 2e 20 69 20 77 69 6c 6c 20 73 65 6e 64 20 79 6f 75 20 64 65 63 72 79 74 69 6f 6e 20 74 6f 6f 6c } //1 email ITSEMAIL . i will send you decrytion tool
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=14
 
}