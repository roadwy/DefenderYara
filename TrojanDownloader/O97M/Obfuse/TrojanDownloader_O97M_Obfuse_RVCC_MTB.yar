
rule TrojanDownloader_O97M_Obfuse_RVCC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVCC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 73 74 72 72 65 76 65 72 73 65 28 65 6e 63 29 66 6f 72 71 3d 31 74 6f 6c 65 6e 28 65 6e 63 29 65 3d 6d 69 64 28 65 6e 63 2c 71 2c 31 29 61 70 70 64 61 74 61 3d 74 65 6d 70 26 63 68 72 28 61 73 63 28 65 29 2d 31 29 6e 65 78 74 } //1 =strreverse(enc)forq=1tolen(enc)e=mid(enc,q,1)appdata=temp&chr(asc(e)-1)next
		$a_01_1 = {2e 6f 70 65 6e 22 67 65 74 22 2c 6a 6e 62 69 68 62 6e 69 6c 62 6a 68 76 67 66 76 67 68 62 28 22 71 7e 7e 7a 67 3c 3c 66 61 3b 3e 62 63 3b 3f 62 40 3b 63 65 67 62 63 64 66 3c 74 70 72 70 7d 76 70 78 7d 75 7e 71 78 7d 3c 74 7d 75 72 74 70 74 71 72 74 71 7d 72 71 74 72 75 74 71 70 7e 74 71 70 70 7c 74 7d 70 71 6f 70 74 6f 70 3c 7d 3b 6e 6e 22 29 } //1 .open"get",jnbihbnilbjhvgfvghb("q~~zg<<fa;>bc;?b@;cegbcdf<tprp}vpx}u~qx}<t}urtptqrtq}rqtrutqp~tqpp|t}pqoptop<};nn")
		$a_01_2 = {3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //1 =createobject("wscript.shell")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}