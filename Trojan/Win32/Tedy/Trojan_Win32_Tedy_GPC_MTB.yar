
rule Trojan_Win32_Tedy_GPC_MTB{
	meta:
		description = "Trojan:Win32/Tedy.GPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {63 00 75 00 6e 00 67 00 75 00 2e 00 6f 00 73 00 73 00 2d 00 63 00 6e 00 2d 00 62 00 65 00 69 00 6a 00 69 00 6e 00 67 00 2e 00 61 00 6c 00 69 00 79 00 75 00 6e 00 63 00 73 00 2e 00 63 00 6f 00 6d 00 2f 00 70 00 61 00 79 00 6c 00 6f 00 61 00 64 00 2e 00 62 00 69 00 6e 00 } //02 00  cungu.oss-cn-beijing.aliyuncs.com/payload.bin
		$a_01_1 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 53 00 68 00 65 00 6c 00 6c 00 63 00 6f 00 64 00 65 00 } //00 00  DownloadShellcode
	condition:
		any of ($a_*)
 
}