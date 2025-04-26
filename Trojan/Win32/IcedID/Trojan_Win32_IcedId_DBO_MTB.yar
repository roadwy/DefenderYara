
rule Trojan_Win32_IcedId_DBO_MTB{
	meta:
		description = "Trojan:Win32/IcedId.DBO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 07 00 00 "
		
	strings :
		$a_81_0 = {68 35 57 67 6d 37 30 39 6f 54 59 5a 4b 63 50 } //1 h5Wgm709oTYZKcP
		$a_81_1 = {53 71 79 38 58 53 76 35 4b 7a 4c 5a 4e 49 79 6a 4c 5a 36 64 46 77 41 65 38 49 32 4b 6f } //1 Sqy8XSv5KzLZNIyjLZ6dFwAe8I2Ko
		$a_81_2 = {43 77 68 62 67 59 43 54 79 75 46 4b 4e 62 70 75 36 69 32 70 32 57 53 61 4c 68 } //1 CwhbgYCTyuFKNbpu6i2p2WSaLh
		$a_81_3 = {51 61 41 6d 44 3f 56 58 77 52 53 52 62 67 33 } //1 QaAmD?VXwRSRbg3
		$a_81_4 = {70 4f 41 74 50 52 57 53 4f 79 75 52 56 73 38 4b 5a 52 41 4c 48 63 53 6d 59 } //1 pOAtPRWSOyuRVs8KZRALHcSmY
		$a_81_5 = {35 59 4f 35 42 6f 55 6f 69 45 50 6e 4e 6b 67 35 32 6d 70 77 45 41 58 } //1 5YO5BoUoiEPnNkg52mpwEAX
		$a_81_6 = {43 4a 36 64 42 71 6e 41 51 5a 33 50 38 59 40 } //1 CJ6dBqnAQZ3P8Y@
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=1
 
}