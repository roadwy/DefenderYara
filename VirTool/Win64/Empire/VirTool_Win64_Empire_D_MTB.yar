
rule VirTool_Win64_Empire_D_MTB{
	meta:
		description = "VirTool:Win64/Empire.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_80_0 = {2d 6a 6f 69 6e 5b 43 68 61 72 5b 5d 5d 28 26 20 24 52 20 24 64 61 74 61 20 28 24 49 56 2b 24 4b 29 29 7c 49 45 58 } //-join[Char[]](& $R $data ($IV+$K))|IEX  01 00 
		$a_80_1 = {24 5f 2d 62 78 6f 72 24 73 5b 28 24 73 5b 24 69 5d 2b 24 73 5b 24 68 5d 29 25 32 35 36 5d 7d 7d } //$_-bxor$s[($s[$i]+$s[$h])%256]}}  01 00 
		$a_80_2 = {3d 5b 73 79 73 74 65 6d 2e 74 65 78 74 2e 65 6e 63 6f 64 69 6e 67 5d 3a 3a 61 73 63 69 69 2e 67 65 74 62 79 74 65 73 28 27 } //=[system.text.encoding]::ascii.getbytes('  01 00 
		$a_80_3 = {24 73 65 72 2b 24 74 } //$ser+$t  01 00 
		$a_80_4 = {43 6f 6e 76 65 72 74 5d 3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 } //Convert]::FromBase64String(  01 00 
		$a_80_5 = {25 7b 24 4a 3d 28 24 4a 2b 24 53 5b 24 5f 5d 2b 24 4b 5b 24 5f 25 24 4b 2e 43 6f 75 6e 74 5d 29 25 32 35 36 } //%{$J=($J+$S[$_]+$K[$_%$K.Count])%256  01 00 
		$a_80_6 = {2e 70 72 6f 78 79 3d 5b 73 79 73 74 65 6d 2e 6e 65 74 2e 77 65 62 72 65 71 75 65 73 74 5d 3a 3a 64 65 66 61 75 6c 74 77 65 62 70 72 6f 78 79 3b } //.proxy=[system.net.webrequest]::defaultwebproxy;  00 00 
	condition:
		any of ($a_*)
 
}