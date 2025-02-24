
rule Trojan_Win32_Neoreblamy_BAH_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.BAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {6e 79 57 55 53 4b 52 51 59 4e 57 50 61 4b 49 7a 74 46 62 71 4d 66 6f 54 4c 59 71 68 6c 6e 6e 43 57 68 } //2 nyWUSKRQYNWPaKIztFbqMfoTLYqhlnnCWh
		$a_01_1 = {46 42 6a 43 46 55 58 78 72 6f 6e 64 68 74 61 5a 62 45 6f 4e 47 48 5a 44 44 76 78 52 67 } //1 FBjCFUXxrondhtaZbEoNGHZDDvxRg
		$a_01_2 = {42 5a 78 72 4c 74 72 61 69 70 45 6e 42 74 54 4e 51 6f 66 52 49 69 77 43 67 73 41 52 70 } //1 BZxrLtraipEnBtTNQofRIiwCgsARp
		$a_01_3 = {42 62 41 42 48 65 46 48 6e 46 56 69 47 53 4a 4b 65 58 79 65 46 46 6c 47 4a 4d 4f 64 } //1 BbABHeFHnFViGSJKeXyeFFlGJMOd
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}