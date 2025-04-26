
rule Trojan_BAT_CryptInject_SL_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {51 57 52 6b 53 57 35 51 63 6d 39 6a 5a 58 4e 7a 4d 7a 49 75 5a 58 68 6c } //1 QWRkSW5Qcm9jZXNzMzIuZXhl
		$a_01_1 = {55 6b 56 57 52 55 52 56 53 56 5a 4e 28 56 6d 6c 79 64 48 56 68 62 43 42 6c 62 6e 5a 70 63 6d 39 75 62 57 56 75 64 43 42 6b 5a 58 52 6c 59 33 52 6c 5a 43 45 3d } //1 UkVWRURVSVZN(VmlydHVhbCBlbnZpcm9ubWVudCBkZXRlY3RlZCE=
		$a_01_2 = {4f 6c 70 76 62 6d 55 75 53 57 52 6c 62 6e 52 70 5a 6d 6c 6c 63 67 3d 3d } //1 OlpvbmUuSWRlbnRpZmllcg==
		$a_01_3 = {55 32 4a 70 5a 55 52 73 62 43 35 6b 62 47 77 3d } //1 U2JpZURsbC5kbGw=
		$a_01_4 = {65 7a 41 36 65 44 4a 39 28 4c 33 52 79 59 6d 6c 73 5a 54 74 6a 62 32 31 77 62 32 35 6c 62 6e 51 76 59 57 52 6b 62 32 35 7a 4c 6e 68 68 62 57 77 3d } //1 ezA6eDJ9(L3RyYmlsZTtjb21wb25lbnQvYWRkb25zLnhhbWw=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}