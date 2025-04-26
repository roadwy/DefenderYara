
rule Trojan_Win64_Lazy_IZ_MTB{
	meta:
		description = "Trojan:Win64/Lazy.IZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_81_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //2 Go build ID:
		$a_81_1 = {65 4f 39 46 6a 52 45 78 51 39 47 39 49 33 52 54 7a 44 41 45 59 68 75 53 35 4b 46 79 35 52 59 75 64 72 6e 43 76 4b 53 72 38 5a 30 3d } //2 eO9FjRExQ9G9I3RTzDAEYhuS5KFy5RYudrnCvKSr8Z0=
		$a_81_2 = {49 4c 61 39 6a 31 6f 6e 41 41 4d 61 64 42 73 79 79 55 4a 76 35 63 61 63 6b 38 59 31 57 54 32 36 79 4c 6a 2f 56 2b 75 6c 4b 70 38 3d } //1 ILa9j1onAAMadBsyyUJv5cack8Y1WT26yLj/V+ulKp8=
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1) >=5
 
}