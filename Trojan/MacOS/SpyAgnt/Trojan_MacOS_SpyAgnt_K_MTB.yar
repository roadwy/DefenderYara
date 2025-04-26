
rule Trojan_MacOS_SpyAgnt_K_MTB{
	meta:
		description = "Trojan:MacOS/SpyAgnt.K!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {72 75 6e 74 69 6d 65 2e 70 65 72 73 69 73 74 65 6e 74 61 6c 6c 6f 63 } //1 runtime.persistentalloc
		$a_00_1 = {70 6f 63 2f 70 6b 67 2f 75 74 69 6c 73 2e 55 70 6c 6f 61 64 } //1 poc/pkg/utils.Upload
		$a_00_2 = {63 72 79 70 74 6f 2f 63 69 70 68 65 72 2e 4e 65 77 43 42 43 44 65 63 72 79 70 74 65 72 } //1 crypto/cipher.NewCBCDecrypter
		$a_00_3 = {44 69 61 6c 43 6c 69 65 6e 74 43 6f 6e 6e 50 6f 6f 6c 2e 47 65 74 43 6c 69 65 6e 74 43 6f 6e 6e } //1 DialClientConnPool.GetClientConn
		$a_00_4 = {6f 73 2e 28 2a 50 72 6f 63 65 73 73 29 2e 4b 69 6c 6c } //1 os.(*Process).Kill
		$a_00_5 = {72 75 6e 74 69 6d 65 2e 73 63 61 76 65 6e 67 65 53 6c 65 65 70 } //1 runtime.scavengeSleep
		$a_00_6 = {6d 61 69 6e 2e 65 78 70 6c 6f 69 74 } //1 main.exploit
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}