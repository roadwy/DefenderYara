
rule Trojan_Win32_Emotetcrypt_IM_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.IM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b c8 03 0d 90 01 04 2b 0d 90 01 04 03 0d 90 01 04 2b 0d 90 01 04 2b 0d 90 01 04 a1 90 01 04 0f af 05 90 01 04 03 c8 a1 90 01 04 0f af 05 90 01 04 03 45 08 0f b6 0c 08 8b 45 0c 0f b6 14 10 33 d1 a1 90 01 04 0f af 05 90 01 04 8b 0d 90 00 } //01 00 
		$a_81_1 = {50 69 69 66 47 57 25 45 61 37 33 72 33 69 29 6f 65 75 4a 71 45 71 4f 4e 5f 2b 33 52 78 48 29 65 32 4d 6b 72 32 52 21 5f 6d 6b 34 47 46 44 36 4d 6d 2b 58 46 5f } //00 00  PiifGW%Ea73r3i)oeuJqEqON_+3RxH)e2Mkr2R!_mk4GFD6Mm+XF_
	condition:
		any of ($a_*)
 
}