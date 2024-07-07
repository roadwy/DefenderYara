
rule Trojan_Win32_Emotetcrypt_GG_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b c1 2b 05 90 01 04 03 05 90 01 04 2b 05 90 01 04 03 05 90 01 04 8b 0d 90 01 04 0f af 0d 90 01 04 03 05 90 01 04 03 c8 2b 0d 90 01 04 03 0d 90 01 04 03 0d 90 01 04 8b 45 08 0f b6 0c 08 8b 45 0c 0f b6 14 10 33 d1 90 00 } //1
		$a_81_1 = {29 4b 50 2a 66 78 36 41 61 76 78 47 42 23 38 39 67 48 55 5f 34 77 3f 28 46 70 24 4b 4b 6a 39 78 71 6c 35 75 63 48 3f 36 4e 73 75 2b 5e 31 29 37 75 6d 32 37 77 37 4f 35 71 4d 21 3f 34 39 61 62 52 2a 38 79 42 2b 65 38 } //1 )KP*fx6AavxGB#89gHU_4w?(Fp$KKj9xql5ucH?6Nsu+^1)7um27w7O5qM!?49abR*8yB+e8
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}