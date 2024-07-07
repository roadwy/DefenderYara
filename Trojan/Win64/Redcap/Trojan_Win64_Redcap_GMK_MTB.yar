
rule Trojan_Win64_Redcap_GMK_MTB{
	meta:
		description = "Trojan:Win64/Redcap.GMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {71 65 64 69 73 5f 6d 62 75 6c 6b 5f 72 65 70 6c 79 5f 7a 69 70 70 65 64 5f 6b 65 79 73 5f 64 62 6c } //1 qedis_mbulk_reply_zipped_keys_dbl
		$a_01_1 = {70 68 70 5f 72 65 64 69 73 2e 64 6c 6c } //1 php_redis.dll
		$a_01_2 = {71 6c 75 73 74 65 72 5f 6d 62 75 6c 6b 5f 7a 69 70 73 74 72 5f 72 65 73 70 } //1 qluster_mbulk_zipstr_resp
		$a_01_3 = {71 65 64 69 73 5f 73 6f 63 6b 5f 63 6f 6e 6e 65 63 74 } //1 qedis_sock_connect
		$a_01_4 = {71 65 64 69 73 5f 70 6f 6f 6c 5f 67 65 74 5f 73 6f 63 6b } //1 qedis_pool_get_sock
		$a_01_5 = {71 6c 75 73 74 65 72 5f 67 65 6e 5f 6d 62 75 6c 6b 5f 72 65 73 70 } //1 qluster_gen_mbulk_resp
		$a_01_6 = {71 65 64 69 73 5f 73 6f 63 6b 5f 72 65 61 64 5f 6d 75 6c 74 69 62 75 6c 6b 5f 6d 75 6c 74 69 5f 72 65 70 6c 79 5f 6c 6f 6f 70 } //1 qedis_sock_read_multibulk_multi_reply_loop
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}