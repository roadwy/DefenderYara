
rule PWS_Win32_Bropaler_A_bit{
	meta:
		description = "PWS:Win32/Bropaler.A!bit,SIGNATURE_TYPE_PEHSTR,09 00 09 00 06 00 00 "
		
	strings :
		$a_01_0 = {2f 6e 65 77 67 61 74 65 2e 70 68 70 } //1 /newgate.php
		$a_01_1 = {2f 67 61 74 65 2e 70 68 70 } //1 /gate.php
		$a_01_2 = {5c 6c 63 78 2e 74 78 74 } //2 \lcx.txt
		$a_01_3 = {6e 61 6d 65 3d 22 6d 79 66 69 6c 65 22 3b 20 66 69 6c 65 6e 61 6d 65 } //2 name="myfile"; filename
		$a_01_4 = {6d 6f 7a 69 6c 6c 61 73 74 65 61 6c 65 72 } //2 mozillastealer
		$a_01_5 = {65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 } //2 encryptedPassword
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=9
 
}