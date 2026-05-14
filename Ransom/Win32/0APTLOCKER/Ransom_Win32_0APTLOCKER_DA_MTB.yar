
rule Ransom_Win32_0APTLOCKER_DA_MTB{
	meta:
		description = "Ransom:Win32/0APTLOCKER.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_81_0 = {3a 3a 3a 20 30 41 50 54 20 4c 4f 43 4b 45 52 20 3a 3a 3a } //10 ::: 0APT LOCKER :::
		$a_81_1 = {21 21 21 20 41 4c 4c 20 59 4f 55 52 20 46 49 4c 45 53 20 41 52 45 20 45 4e 43 52 59 50 54 45 44 20 21 21 21 } //1 !!! ALL YOUR FILES ARE ENCRYPTED !!!
		$a_81_2 = {57 61 6c 6c 70 61 70 65 72 20 73 75 63 63 65 73 73 66 75 6c 6c 79 20 63 68 61 6e 67 65 } //1 Wallpaper successfully change
		$a_81_3 = {44 6f 77 6e 6c 6f 61 64 20 61 6e 64 20 69 6e 73 74 61 6c 6c 20 54 6f 72 20 42 72 6f 77 73 65 72 3a } //1 Download and install Tor Browser:
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=13
 
}