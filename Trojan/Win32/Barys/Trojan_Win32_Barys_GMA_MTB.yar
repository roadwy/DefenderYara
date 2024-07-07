
rule Trojan_Win32_Barys_GMA_MTB{
	meta:
		description = "Trojan:Win32/Barys.GMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {45 4c 32 52 38 52 50 76 35 4c 6d 77 46 50 50 } //1 EL2R8RPv5LmwFPP
		$a_01_1 = {61 6d 61 4e 34 6e 75 78 76 41 77 70 4f 58 } //1 amaN4nuxvAwpOX
		$a_01_2 = {76 41 4b 41 33 71 77 51 6b 48 4f 70 45 58 76 38 } //1 vAKA3qwQkHOpEXv8
		$a_01_3 = {63 65 38 6a 48 48 4a 45 56 73 47 6d 52 79 4e 6a 66 45 43 6a 34 6e 4c } //1 ce8jHHJEVsGmRyNjfECj4nL
		$a_01_4 = {6e 30 31 59 50 38 37 63 79 6f 47 37 39 4d } //1 n01YP87cyoG79M
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}