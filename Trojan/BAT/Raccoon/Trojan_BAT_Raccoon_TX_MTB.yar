
rule Trojan_BAT_Raccoon_TX_MTB{
	meta:
		description = "Trojan:BAT/Raccoon.TX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 55 73 65 72 73 5c 41 6c 65 78 78 5c 44 65 73 6b 74 6f 70 5c 6d 73 6d 73 6d 73 6d 73 6d 2e 70 64 62 } //1 C:\Users\Alexx\Desktop\msmsmsmsm.pdb
		$a_01_1 = {41 00 77 00 65 00 69 00 69 00 77 00 69 00 2e 00 65 00 78 00 65 00 } //1 Aweiiwi.exe
		$a_81_2 = {4f 44 67 7a 5a 47 55 79 5a 54 4d 35 4e 7a 4a 6c 5a 6d 56 6c 4e 77 3d 3d 24 51 58 4e 7a 5a 57 31 69 62 48 6b 67 61 47 46 7a 49 47 4a 6c 5a 57 34 67 64 47 46 74 63 47 56 79 5a 57 51 3d } //1 ODgzZGUyZTM5NzJlZmVlNw==$QXNzZW1ibHkgaGFzIGJlZW4gdGFtcGVyZWQ=
		$a_81_3 = {56 47 68 6c 49 48 42 79 62 32 64 79 59 57 30 67 59 32 46 75 4a 33 51 67 63 33 52 68 63 6e 51 67 59 6d 56 6a 59 58 56 7a 5a 53 42 73 61 57 4a 33 61 57 35 77 64 47 68 79 5a 57 46 6b 4c 54 45 75 5a 47 78 73 49 } //1 VGhlIHByb2dyYW0gY2FuJ3Qgc3RhcnQgYmVjYXVzZSBsaWJ3aW5wdGhyZWFkLTEuZGxsI
		$a_81_4 = {51 32 39 79 62 32 35 76 64 6d 6c 79 64 58 4d 75 51 32 39 79 62 32 35 76 64 6d 6c 79 64 58 4d 3d } //1 Q29yb25vdmlydXMuQ29yb25vdmlydXM=
		$a_81_5 = {35 6e 49 48 52 6f 5a 53 42 77 63 6d 39 6e 63 6d 46 74 49 48 52 76 49 47 5a 70 65 43 42 30 61 47 6c 7a 49 48 42 79 62 32 4a 73 5a 57 30 75 } //1 5nIHRoZSBwcm9ncmFtIHRvIGZpeCB0aGlzIHByb2JsZW0u
	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}