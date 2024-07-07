
rule Trojan_Win32_DllInject_GR_MTB{
	meta:
		description = "Trojan:Win32/DllInject.GR!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 54 3d e8 8d 5d f0 88 55 f0 e8 3d 02 00 00 88 44 3d e8 47 83 ff 04 7c e7 } //1
		$a_01_1 = {4d 32 59 78 4d 47 55 79 4d 32 4a 69 4d 57 45 31 5a 47 5a 6b 4f 57 4d 34 59 32 45 77 4e 6a 45 35 4e 57 55 30 4d 7a 41 30 4d 7a 4d 34 4e 6d 45 35 59 6d 45 30 59 7a 59 7a 59 7a 4d 31 59 57 4d 31 4d 54 68 6d 4e 44 59 7a 59 6d 45 33 4e 6a 68 6d 4d 44 41 78 59 67 3d 3d } //1 M2YxMGUyM2JiMWE1ZGZkOWM4Y2EwNjE5NWU0MzA0MzM4NmE5YmE0YzYzYzM1YWM1MThmNDYzYmE3NjhmMDAxYg==
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}