
rule Trojan_BAT_RedLine_RDBM_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {32 62 37 36 62 36 38 36 2d 39 63 35 61 2d 34 66 34 31 2d 39 34 62 33 2d 31 31 39 63 39 65 35 61 38 64 31 32 } //1 2b76b686-9c5a-4f41-94b3-119c9e5a8d12
		$a_01_1 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 2e 6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 } //1 aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd
		$a_01_2 = {45 43 45 52 68 41 4e 6d 37 6c 38 76 47 48 4f 74 42 58 2e 30 45 42 69 6c 44 59 50 74 75 34 79 61 44 52 31 62 36 } //1 ECERhANm7l8vGHOtBX.0EBilDYPtu4yaDR1b6
		$a_01_3 = {53 50 6f 74 43 7a } //1 SPotCz
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}