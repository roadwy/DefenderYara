
rule Trojan_Win32_Veslorn_D{
	meta:
		description = "Trojan:Win32/Veslorn.D,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 65 72 76 00 b9 a4 b3 cc 31 00 00 44 6f 77 6e 4c 6f 61 64 65 72 00 00 } //1
		$a_01_1 = {7c 00 7c 00 52 00 61 00 76 00 6d 00 6f 00 6e 00 44 00 2e 00 65 00 78 00 65 00 7c 00 7c 00 52 00 61 00 76 00 53 00 74 00 75 00 62 00 2e 00 65 00 78 00 65 00 7c 00 7c 00 4b 00 56 00 58 00 50 00 2e 00 65 00 78 00 65 00 7c 00 7c 00 4b 00 76 00 4d 00 6f 00 6e 00 58 00 50 00 2e 00 65 00 78 00 65 00 7c 00 7c 00 4b 00 56 00 43 00 65 00 6e 00 74 00 65 00 72 00 2e 00 65 00 78 00 65 00 7c 00 7c 00 } //1 ||RavmonD.exe||RavStub.exe||KVXP.exe||KvMonXP.exe||KVCenter.exe||
		$a_01_2 = {68 74 74 70 3a 2f 2f 63 6f 6e 67 73 2e 7a 7a 69 79 75 61 6e 2e 63 6f 6d 2f 31 2e 74 78 74 } //1 http://congs.zziyuan.com/1.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}