
rule Trojan_Win32_Emotet_PBL_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {8a 04 0a 8b 0d ?? ?? ?? ?? 8b 11 8b 4d ?? 33 db 8a 1c 11 33 c3 8b 15 ?? ?? ?? ?? 8b 0a 8b 55 ?? 88 04 0a } //1
		$a_81_1 = {40 76 25 46 34 54 57 46 52 39 51 6c 52 4a 68 76 7a 63 50 23 70 31 4b 66 39 21 4b 50 79 6e 52 6c 59 66 25 63 57 4b 64 55 38 45 77 40 49 5a 64 } //1 @v%F4TWFR9QlRJhvzcP#p1Kf9!KPynRlYf%cWKdU8Ew@IZd
		$a_81_2 = {4b 57 7e 76 6d 49 38 42 51 46 25 70 4b 40 4b 73 74 7a 4e 7e 59 30 37 59 77 43 62 33 5a 44 7b 48 3f 51 58 63 31 44 4c 33 35 66 4e 40 6a 6f 52 39 73 4e 56 55 36 4d 6c 70 6e 35 44 25 63 4a 68 7e 40 36 56 58 31 71 45 32 7d 69 70 } //1 KW~vmI8BQF%pK@KstzN~Y07YwCb3ZD{H?QXc1DL35fN@joR9sNVU6Mlpn5D%cJh~@6VX1qE2}ip
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=1
 
}