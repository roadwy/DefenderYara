
rule Trojan_Win32_Emotetcrypt_GD_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 32 03 c2 89 6c 24 20 99 bd ?? ?? ?? ?? f7 fd 8b 44 24 5c 8b 6c 24 24 83 c5 01 89 6c 24 24 03 d3 03 d1 03 d7 0f b6 14 02 8b 44 24 28 30 54 28 ff } //1
		$a_81_1 = {34 58 47 36 4b 25 46 4a 41 68 37 48 35 6c 5e 4f 72 76 23 3c 41 65 53 31 40 63 4b 6c 77 66 69 44 64 46 55 3e 42 5a 37 4c 41 6c 53 75 5e 33 31 43 43 59 52 39 52 34 58 47 39 6f 61 41 5f 25 77 66 5e 38 } //1 4XG6K%FJAh7H5l^Orv#<AeS1@cKlwfiDdFU>BZ7LAlSu^31CCYR9R4XG9oaA_%wf^8
		$a_03_2 = {0f b6 14 3a 03 c2 99 bd ?? ?? ?? ?? f7 fd 8b 44 24 50 8b 6c 24 1c 03 d6 03 54 24 18 0f b6 14 02 30 54 2b ff 3b 5c 24 58 0f 82 } //1
		$a_81_3 = {61 6b 69 47 4d 61 37 6e 6d 48 4a 6f 49 38 44 49 36 4a 3e 5f 5e 51 37 43 36 59 33 47 6c 47 61 56 34 40 69 37 74 4d 63 76 25 63 56 41 53 3e 36 40 4b 71 4d 48 35 45 34 4c 59 24 36 78 4d 4f 5e 72 48 65 70 2a 72 3f 63 44 5e 43 75 31 3f 29 } //1 akiGMa7nmHJoI8DI6J>_^Q7C6Y3GlGaV4@i7tMcv%cVAS>6@KqMH5E4LY$6xMO^rHep*r?cD^Cu1?)
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_03_2  & 1)*1+(#a_81_3  & 1)*1) >=1
 
}