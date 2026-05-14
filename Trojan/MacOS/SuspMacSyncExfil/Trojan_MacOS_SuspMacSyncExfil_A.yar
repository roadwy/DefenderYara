
rule Trojan_MacOS_SuspMacSyncExfil_A{
	meta:
		description = "Trojan:MacOS/SuspMacSyncExfil.A,SIGNATURE_TYPE_CMDHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_00_0 = {63 00 75 00 72 00 6c 00 20 00 } //4 curl 
		$a_00_1 = {2d 00 58 00 20 00 50 00 4f 00 53 00 54 00 } //4 -X POST
		$a_00_2 = {2d 00 2d 00 6d 00 61 00 78 00 2d 00 74 00 69 00 6d 00 65 00 } //1 --max-time
		$a_00_3 = {61 00 70 00 69 00 2d 00 6b 00 65 00 79 00 3a 00 } //1 api-key:
		$a_00_4 = {20 00 68 00 74 00 74 00 70 00 } //1  http
		$a_00_5 = {2d 00 46 00 20 00 66 00 69 00 6c 00 65 00 3d 00 40 00 2f 00 74 00 6d 00 70 00 2f 00 6f 00 73 00 61 00 6c 00 6f 00 67 00 67 00 69 00 6e 00 67 00 2e 00 7a 00 69 00 70 00 20 00 2d 00 46 00 20 00 62 00 75 00 69 00 6c 00 64 00 74 00 78 00 64 00 3d 00 } //5 -F file=@/tmp/osalogging.zip -F buildtxd=
	condition:
		((#a_00_0  & 1)*4+(#a_00_1  & 1)*4+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*5) >=15
 
}